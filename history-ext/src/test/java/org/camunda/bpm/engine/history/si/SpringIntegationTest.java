package org.camunda.bpm.engine.history.si;

import org.camunda.bpm.engine.history.EventBuilder;
import org.camunda.bpm.engine.history.HistoryEventMessage;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.integration.Message;
import org.springframework.integration.MessageChannel;
import org.springframework.integration.MessagingException;
import org.springframework.integration.core.MessageHandler;
import org.springframework.integration.core.SubscribableChannel;
import org.springframework.integration.endpoint.AbstractEndpoint;
import org.springframework.integration.endpoint.EventDrivenConsumer;
import org.springframework.integration.support.MessageBuilder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * 
 * Spring-Integeration should be an good citizen for our requirements.
 * 
 * @author jbellmann
 * 
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
public class SpringIntegationTest {

  private static final Logger LOG = LoggerFactory.getLogger(SpringIntegationTest.class);

  @Autowired
  @Qualifier("historyEventMessageChannel")
  private MessageChannel historyEventMessageChannel;

  @Autowired
  private HistoryEventMessageGateway historyEventMessageGateway;

  @Before
  public void checkDeps() {
    Assert.assertNotNull(historyEventMessageChannel);
    Assert.assertNotNull(historyEventMessageGateway);
  }

  @Test
  public void test() throws InterruptedException {
    Message<HistoryEventMessage> message = MessageBuilder.withPayload(new HistoryEventMessage(EventBuilder.buildHistoricActivityInstanceEventEntity()))
        .setHeader("hostname", "localhost").setHeader("inputStyle", "CHANNEL").build();
    Assert.assertTrue(historyEventMessageChannel.send(message));

    historyEventMessageGateway.send(new HistoryEventMessage(EventBuilder.buildHistoricProcessInstanceEventEntity()));

    Thread.sleep(3 * 1000);
  }

  @Configuration
  @ImportResource("classpath:/si-context.xml")
  static class TesConfig {

    @Autowired
    @Qualifier("inChannel")
    private SubscribableChannel inChannel;

    /**
     * Consumes the Messages.
     * 
     * @return
     */
    @Bean
    public AbstractEndpoint consumer() {

      EventDrivenConsumer c = new EventDrivenConsumer(inChannel, messageHandler());
      return c;

    }

    @Bean
    public MessageHandler messageHandler() {
      return new MessageHandler() {

        @Override
        public void handleMessage(Message<?> message) throws MessagingException {
          LOG.debug("----- MESSAGE_ARRIVED -----");
          LOG.debug("HEADER: " + message.getHeaders().toString());
          LOG.debug(message.getPayload().toString());
          LOG.debug("----- MESSAGE_END -----");
        }
      };
    }
  }
}
